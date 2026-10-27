// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MEASURE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_MEASURE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** gpu_measured() stays this value. A local sample list is not a GPU measurement. */
inline constexpr bool kSwarmMeasureGpuMeasured = false;

/** gpu_passed() stays this value. No GPU benchmark is claimed. */
inline constexpr bool kSwarmMeasureGpuPassed = false;

/**
 * windows_passed() stays this value.
 * Storing windows evidence does not change it. No method sets it true.
 */
inline constexpr bool kSwarmMeasureWindowsPassed = false;

/** launched() stays this value. Nothing is started. */
inline constexpr bool kSwarmMeasureLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmMeasureGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmMeasureBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmMeasureAutomaticSpend[] = "0";

/** bytes_moved() stays this value. No bytes are moved. */
inline constexpr int64_t kSwarmMeasureBytesMoved = 0;

static_assert(!kSwarmMeasureGpuMeasured, "a sample list is not a gpu measurement");
static_assert(!kSwarmMeasureGpuPassed, "this record does not pass a gpu benchmark");
static_assert(!kSwarmMeasureWindowsPassed, "this record does not pass windows");
static_assert(!kSwarmMeasureLaunched, "this record does not launch");
static_assert(!kSwarmMeasureGpu, "this record does not use a gpu");
static_assert(!kSwarmMeasureBroadcast, "this record does not broadcast");
static_assert(kSwarmMeasureAutomaticSpend[0] == '0' && kSwarmMeasureAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmMeasureBytesMoved == 0, "bytes moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MEASURE_LIMITS_H
