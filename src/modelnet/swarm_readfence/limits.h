// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_READFENCE_LIMITS_H

#include <array>
#include <cstdint>

namespace modelnet {

/**
 * Names Probe can mark INSTALLED when present is true.
 * Any other name is ENGINE_ABSENT, including when present is true.
 */
inline constexpr std::array<const char*, 6> kSwarmReadEngineNames{{
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
}};

/**
 * Largest size Accept will store.
 * size <= 0 or size above this value is TRUNCATED and stores nothing.
 * Equality with this value is stored.
 */
inline constexpr int64_t kSwarmReadAcceptMax = 33554432;

/** This plane moves no bytes. A missing engine moves none. */
inline constexpr int64_t kSwarmReadBytesMoved = 0;

/** Probe does not qualify an engine. */
inline constexpr bool kSwarmReadQualified = false;

/** Probe does not advertise an engine. */
inline constexpr bool kSwarmReadAdvertised = false;

/** This plane does not start a process. */
inline constexpr bool kSwarmReadProcessStarted = false;

/** This plane does not allocate a CUDA buffer. */
inline constexpr bool kSwarmReadCudaBuffer = false;

static_assert(kSwarmReadEngineNames.size() == 6, "six known cache engines");
static_assert(kSwarmReadAcceptMax == 33554432, "accept stores at most 33554432");
static_assert(kSwarmReadAcceptMax > 0, "a non-positive size is truncated");
static_assert(kSwarmReadBytesMoved == 0, "a missing engine moves no bytes");
static_assert(!kSwarmReadQualified, "probe does not qualify");
static_assert(!kSwarmReadAdvertised, "probe does not advertise");
static_assert(!kSwarmReadProcessStarted, "a cache read does not start a process");
static_assert(!kSwarmReadCudaBuffer, "a cache read does not allocate a CUDA buffer");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_LIMITS_H
