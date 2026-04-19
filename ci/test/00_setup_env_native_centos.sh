#!/usr/bin/env bash
#
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_centos
export CI_IMAGE_NAME_TAG="quay.io/centos/centos:stream10"
export CI_BASE_PACKAGES="gcc-c++ glibc-devel libstdc++-devel ccache make git python3 python3-pip which patch xz procps-ng rsync coreutils bison e2fsprogs cmake dash libicns-utils librsvg2-tools ImageMagick"
export PIP_PACKAGES="pyzmq"
# Keep the CentOS lane lean to avoid hosted-runner OOM kills/hangs. This lane is
# primarily a build + fork-critical unit coverage smoke, not a full matrix.
export DEP_OPTS="${DEP_OPTS:-NO_QT=1}"
# GitHub hosted runners can OOM during the CentOS (Debug + GUI + depends) lane
# if we build with full parallelism. Cap by default to keep the job stable and
# ensure we get actionable logs instead of abrupt runner termination.
export MAKEJOBS="${MAKEJOBS:--j4}"
export GOAL="install"
export BITCOIN_CONFIG="-DWITH_ZMQ=ON -DBUILD_GUI=OFF -DREDUCE_EXPORTS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF"

# This lane's primary purpose is build + fork-specific unit coverage on CentOS.
# Full functional coverage is exercised in the ubuntu lanes; running functional
# tests here has been a repeated source of runner OOM/hangs with missing logs.
export RUN_FUNCTIONAL_TESTS="false"
# Keep unit coverage focused and deterministic to reduce runtime/memory.
export CTEST_REGEX="${CTEST_REGEX:-^(pq_.*|matmul_.*|pow_tests)$}"
# Tighten timeouts so hangs fail fast rather than burning a full job window.
export TEST_RUNNER_TIMEOUT_FACTOR="${TEST_RUNNER_TIMEOUT_FACTOR:-10}"
