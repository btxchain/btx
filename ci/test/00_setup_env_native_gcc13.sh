#!/usr/bin/env bash
#
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Build+test lane pinned to GCC 13 (Ubuntu LTS default). Catches ill-formed
# C++ that newer host compilers (e.g. GCC 15) silently accept.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_gcc13
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export PACKAGES="gcc-13 g++-13 python3-zmq libevent-dev libboost-dev libsqlite3-dev libminiupnpc-dev libzmq3-dev"
export DEP_OPTS="NO_QT=1 NO_UPNP=1 DEBUG=1 CC=gcc-13 CXX=g++-13"
export NO_DEPENDS=1
export GOAL="install"
export BITCOIN_CONFIG="\
 -DCMAKE_BUILD_TYPE=Debug \
 -DBUILD_GUI=OFF \
 -DBUILD_BENCH=OFF \
 -DBUILD_FUZZ_BINARY=OFF \
 -DCMAKE_C_COMPILER=gcc-13 \
 -DCMAKE_CXX_COMPILER=g++-13 \
 -DAPPEND_CPPFLAGS='-DDEBUG_LOCKORDER' \
"
export RUN_FUNCTIONAL_TESTS="false"
# Keep the lane focused on the suites that recently shipped silent gaps.
export CTEST_REGEX="${CTEST_REGEX:-^(pq_.*|matmul_.*|pow_tests|validation_chainstatemanager_tests)$}"
export TEST_RUNNER_TIMEOUT_FACTOR="${TEST_RUNNER_TIMEOUT_FACTOR:-10}"
