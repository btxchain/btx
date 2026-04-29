#!/usr/bin/env bash
#
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8
export CI_IMAGE_LABEL="bitcoin-ci-test"

set -o errexit -o pipefail -o xtrace

# Parallel CI jobs can share CONTAINER_NAME (e.g. tidy in two workflows).
# Derive a per-job runtime container/env-file name to avoid collisions.
CI_INSTANCE_SUFFIX="${GITHUB_RUN_ID:-local}-${GITHUB_JOB:-job}-${GITHUB_RUN_ATTEMPT:-0}-$$"
CI_INSTANCE_SUFFIX="$(printf '%s' "${CI_INSTANCE_SUFFIX}" | tr -cd 'A-Za-z0-9_.-')"
CONTAINER_INSTANCE_NAME="${CONTAINER_NAME}-${CI_INSTANCE_SUFFIX}"
CI_ENV_FILE="/tmp/env-${USER}-${CONTAINER_INSTANCE_NAME}"
CI_CONTAINER_ID=""

cleanup_ci_container() {
  local exit_code=$?
  set +o errexit
  if [ -n "${CI_CONTAINER_ID:-}" ]; then
    echo "Stop and remove CI container by ID"
    docker container kill "${CI_CONTAINER_ID}" || true
  fi
  if [ -n "${CI_ENV_FILE:-}" ] && [ -f "${CI_ENV_FILE}" ]; then
    rm -f "${CI_ENV_FILE}" || true
  fi
  exit "${exit_code}"
}
trap cleanup_ci_container EXIT INT TERM

if [ -z "$DANGER_RUN_CI_ON_HOST" ]; then
  # Export all env vars to avoid missing some.
  # Though, exclude those with newlines to avoid parsing problems.
  python3 -c 'import os; [print(f"{key}={value}") for key, value in os.environ.items() if "\n" not in value and "HOME" != key and "PATH" != key and "USER" != key]' | tee "${CI_ENV_FILE}"

  # Env vars during the build can not be changed. For example, a modified
  # $MAKEJOBS is ignored in the build process. Use --cpuset-cpus as an
  # approximation to respect $MAKEJOBS somewhat, if cpuset is available.
  MAYBE_CPUSET=""
  if [ "$HAVE_CGROUP_CPUSET" ]; then
    MAYBE_CPUSET="--cpuset-cpus=$( python3 -c "import random;P=$( nproc );M=min(P,int('$MAKEJOBS'.lstrip('-j')));print(','.join(map(str,sorted(random.sample(range(P),M)))))" )"
  fi
  echo "Creating $CI_IMAGE_NAME_TAG container to run in"

  # Use buildx unconditionally
  # Using buildx is required to properly load the correct driver, for use with registry caching. Neither build, nor BUILDKIT=1 currently do this properly
  # shellcheck disable=SC2086
  docker buildx build \
      --progress=plain \
      --file "${BASE_READ_ONLY_DIR}/ci/test_imagefile" \
      --build-arg "CI_IMAGE_NAME_TAG=${CI_IMAGE_NAME_TAG}" \
      --build-arg "FILE_ENV=${FILE_ENV}" \
      --build-arg "BASE_ROOT_DIR=${BASE_ROOT_DIR}" \
      $MAYBE_CPUSET \
      --platform="${CI_IMAGE_PLATFORM}" \
      --label="${CI_IMAGE_LABEL}" \
      --tag="${CONTAINER_NAME}" \
      $DOCKER_BUILD_CACHE_ARG \
      "${BASE_READ_ONLY_DIR}"

  docker volume create "${CONTAINER_NAME}_ccache" || true
  docker volume create "${CONTAINER_NAME}_depends" || true
  docker volume create "${CONTAINER_NAME}_depends_sources" || true
  docker volume create "${CONTAINER_NAME}_previous_releases" || true

  CI_CCACHE_MOUNT="type=volume,src=${CONTAINER_NAME}_ccache,dst=$CCACHE_DIR"
  CI_DEPENDS_MOUNT="type=volume,src=${CONTAINER_NAME}_depends,dst=$DEPENDS_DIR/built"
  CI_DEPENDS_SOURCES_MOUNT="type=volume,src=${CONTAINER_NAME}_depends_sources,dst=$DEPENDS_DIR/sources"
  CI_PREVIOUS_RELEASES_MOUNT="type=volume,src=${CONTAINER_NAME}_previous_releases,dst=$PREVIOUS_RELEASES_DIR"
  CI_BUILD_MOUNT=""

  if [ "$DANGER_CI_ON_HOST_FOLDERS" ]; then
    # ensure the directories exist
    mkdir -p "${CCACHE_DIR}"
    mkdir -p "${DEPENDS_DIR}/built"
    mkdir -p "${DEPENDS_DIR}/sources"
    mkdir -p "${PREVIOUS_RELEASES_DIR}"

    CI_CCACHE_MOUNT="type=bind,src=${CCACHE_DIR},dst=$CCACHE_DIR"
    CI_DEPENDS_MOUNT="type=bind,src=${DEPENDS_DIR}/built,dst=$DEPENDS_DIR/built"
    CI_DEPENDS_SOURCES_MOUNT="type=bind,src=${DEPENDS_DIR}/sources,dst=$DEPENDS_DIR/sources"
    CI_PREVIOUS_RELEASES_MOUNT="type=bind,src=${PREVIOUS_RELEASES_DIR},dst=$PREVIOUS_RELEASES_DIR"
    # BASE_BUILD_DIR is optional. Avoid creating/binding an empty path when unset.
    if [ -n "${BASE_BUILD_DIR:-}" ]; then
      mkdir -p "${BASE_BUILD_DIR}"
      CI_BUILD_MOUNT="--mount type=bind,src=${BASE_BUILD_DIR},dst=${BASE_BUILD_DIR}"
    fi
  fi

  if [ "$DANGER_CI_ON_HOST_CCACHE_FOLDER" ]; then
   # Temporary exclusion for https://github.com/bitcoin/bitcoin/issues/31108
   # to allow CI configs and envs generated in the past to work for a bit longer.
   # Can be removed in March 2025.
   if [ "${CCACHE_DIR}" != "/tmp/ccache_dir" ]; then
    if [ ! -d "${CCACHE_DIR}" ]; then
      echo "Error: Directory '${CCACHE_DIR}' must be created in advance."
      exit 1
    fi
    CI_CCACHE_MOUNT="type=bind,src=${CCACHE_DIR},dst=${CCACHE_DIR}"
   fi # End temporary exclusion
  fi

  docker network create --ipv6 --subnet 1111:1111::/112 ci-ip6net || true

  if [ -n "${RESTART_CI_DOCKER_BEFORE_RUN}" ] ; then
    echo "Restart docker before run to stop and clear all containers started with --rm"
    podman container rm --force --all  # Similar to "systemctl restart docker"

    # Still prune everything in case the filtered pruning doesn't work, or if labels were not set
    # on a previous run. Belt and suspenders approach, should be fine to remove in the future.
    # Prune images used by --external containers (e.g. build containers) when
    # using podman.
    echo "Prune all dangling images"
    podman image prune --force --external
  fi
  echo "Prune all dangling $CI_IMAGE_LABEL images"
  # When detecting podman-docker, `--external` should be added.
  docker image prune --force --filter "label=$CI_IMAGE_LABEL"

  # Append $USER to /tmp/env to support multi-user systems and $CONTAINER_NAME
  # to allow support starting multiple runs simultaneously by the same user.
  # shellcheck disable=SC2086
  CI_CONTAINER_ID=$(docker run --cap-add LINUX_IMMUTABLE $CI_CONTAINER_CAP --rm --interactive --detach --tty \
                  --mount "type=bind,src=$BASE_READ_ONLY_DIR,dst=$BASE_READ_ONLY_DIR,readonly" \
                  --mount "${CI_CCACHE_MOUNT}" \
                  --mount "${CI_DEPENDS_MOUNT}" \
                  --mount "${CI_DEPENDS_SOURCES_MOUNT}" \
                  --mount "${CI_PREVIOUS_RELEASES_MOUNT}" \
                  ${CI_BUILD_MOUNT} \
                  --env-file "${CI_ENV_FILE}" \
                  --name "${CONTAINER_INSTANCE_NAME}" \
                  --network ci-ip6net \
                  --platform="${CI_IMAGE_PLATFORM}" \
                  "$CONTAINER_NAME")
  export CI_CONTAINER_ID
  export CI_EXEC_CMD_PREFIX="docker exec ${CI_CONTAINER_ID}"
else
  echo "Running on host system without docker wrapper"
  echo "Create missing folders"
  mkdir -p "${CCACHE_DIR}"
  mkdir -p "${PREVIOUS_RELEASES_DIR}"
fi

if [ "$CI_OS_NAME" == "macos" ]; then
  IN_GETOPT_BIN="$(brew --prefix gnu-getopt)/bin/getopt"
  export IN_GETOPT_BIN
fi

CI_EXEC () {
  $CI_EXEC_CMD_PREFIX bash -c "export PATH=\"/path_with space:${BINS_SCRATCH_DIR}:${BASE_ROOT_DIR}/ci/retry:\$PATH\" && cd \"${BASE_ROOT_DIR}\" && $*"
}
export -f CI_EXEC

# Normalize all folders to BASE_ROOT_DIR.
# Exclude local build/temp artifacts to keep host->container sync bounded.
RSYNC_EXCLUDES=(
  "build/"
  "build-*/"
  "ci/scratch/"
  ".tmp*/"
  ".codex-swarm/"
  ".ci-fuzz-corpus/"
  ".ci-lint-venv*/"
)
if [[ -n "${CI_RSYNC_EXTRA_EXCLUDES:-}" ]]; then
  IFS=':' read -r -a extra_excludes <<< "${CI_RSYNC_EXTRA_EXCLUDES}"
  for item in "${extra_excludes[@]}"; do
    [[ -n "${item}" ]] && RSYNC_EXCLUDES+=("${item}")
  done
fi

RSYNC_CMD="rsync --archive --stats --human-readable"
for pattern in "${RSYNC_EXCLUDES[@]}"; do
  RSYNC_CMD+=" --exclude=$(printf '%q' "${pattern}")"
done
RSYNC_CMD+=" $(printf '%q' "${BASE_READ_ONLY_DIR}/") $(printf '%q' "${BASE_ROOT_DIR}")"

if [[ ! -d "${BASE_READ_ONLY_DIR}" ]]; then
  echo "Error: source directory '${BASE_READ_ONLY_DIR}' does not exist" >&2
  exit 1
fi
CI_EXEC "${RSYNC_CMD}"
CI_EXEC "${BASE_ROOT_DIR}/ci/test/01_base_install.sh"

# Fixes permission issues when there is a container UID/GID mismatch with the owner
# of the git source code directory.
CI_EXEC git config --global --add safe.directory \"*\"

CI_EXEC mkdir -p "${BINS_SCRATCH_DIR}"

if [[ "${CI_IMAGE_NAME_TAG}" == *centos* ]]; then
  # Hosted runners have historically OOM-killed/hung during this lane, leading to
  # missing job logs. A hard timeout makes failures deterministic and ensures
  # logs are finalized and downloadable.
  : "${CENTOS_RUN_TARGET_TIMEOUT_SEC:=4800}" # 80m
  echo "CentOS lane timeout guard enabled: ${CENTOS_RUN_TARGET_TIMEOUT_SEC}s"
  CI_EXEC timeout --preserve-status --kill-after=60 "${CENTOS_RUN_TARGET_TIMEOUT_SEC}" "${BASE_ROOT_DIR}/ci/test/03_test_script.sh"
else
  CI_EXEC "${BASE_ROOT_DIR}/ci/test/03_test_script.sh"
fi
