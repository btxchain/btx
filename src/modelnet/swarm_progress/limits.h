// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROGRESS_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PROGRESS_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Identical samples required before Stall sets correcting(). */
inline constexpr int64_t kSwarmProgressIdenticalStall = 3;

/** killed() stays this value. A plateau is not a kill. */
inline constexpr bool kSwarmProgressKilled = false;

/** launched() stays this value. Nothing is started. */
inline constexpr bool kSwarmProgressLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmProgressGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmProgressBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmProgressAutomaticSpend[] = "0";

/** bytes_moved() stays this value. No bytes are moved. */
inline constexpr int64_t kSwarmProgressBytesMoved = 0;

static_assert(kSwarmProgressIdenticalStall == 3, "stall requires three identical samples");
static_assert(!kSwarmProgressKilled, "a plateau does not kill");
static_assert(!kSwarmProgressLaunched, "this record does not launch");
static_assert(!kSwarmProgressGpu, "this record does not use a gpu");
static_assert(!kSwarmProgressBroadcast, "this record does not broadcast");
static_assert(kSwarmProgressAutomaticSpend[0] == '0' && kSwarmProgressAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmProgressBytesMoved == 0, "bytes moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROGRESS_LIMITS_H
