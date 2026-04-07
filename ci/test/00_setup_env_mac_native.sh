#!/usr/bin/env bash
export LC_ALL=C
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Keep UTF-8 when present, otherwise avoid invalid locale warnings on macOS hosts.
if locale -a 2>/dev/null | grep -Eiq '^c\.utf-?8$'; then
  export LC_ALL=C.UTF-8
fi

# Homebrew's python@3.12 is marked as externally managed (PEP 668).
# Therefore, `--break-system-packages` is needed.
export CONTAINER_NAME="ci_mac_native"  # macos does not use a container, but the env var is needed for logging
export PIP_PACKAGES="--break-system-packages zmq"
export GOAL="install"
export CMAKE_GENERATOR="Ninja"
export BITCOIN_CONFIG="-DBUILD_GUI=ON -DWITH_ZMQ=ON -DWITH_MINIUPNPC=ON -DREDUCE_EXPORTS=ON"
export CI_OS_NAME="macos"
export NO_DEPENDS=1
export OSX_SDK=""
# Functional coverage is exercised in dedicated BTX readiness lanes; keep this
# GUI/native lane focused on build + unit checks to avoid hosted-runner timeouts.
export RUN_FUNCTIONAL_TESTS=false
# Keep functional-test jobs chatty enough to avoid opaque runner stalls.
export TEST_RUNNER_QUIET=false
# Keep enough headroom for heavy wallet/PQ suites on slower hosted arm64 runners.
export TEST_RUNNER_TIMEOUT_FACTOR=40
