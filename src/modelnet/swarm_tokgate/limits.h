// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane does not run a decode. */
inline constexpr bool kSwarmTokenGateRunning = false;

/** This plane does not launch a process. */
inline constexpr bool kSwarmTokenGateLaunched = false;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmTokenGateGpu = false;

/** This plane does not record a measurement. */
inline constexpr bool kSwarmTokenGateMeasured = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmTokenGateBytesMoved = 0;

/** This plane invents no tokens. */
inline constexpr int64_t kSwarmTokenGateTokens = 0;

/** ttft, p50, and p95 stay at this sentinel. They are not a measurement. */
inline constexpr int64_t kSwarmTokenGateUnmeasuredMs = -1;

static_assert(!kSwarmTokenGateRunning, "token gate does not run");
static_assert(!kSwarmTokenGateLaunched, "token gate does not launch");
static_assert(!kSwarmTokenGateGpu, "token gate does not use a gpu");
static_assert(!kSwarmTokenGateMeasured, "token gate does not measure");
static_assert(kSwarmTokenGateBytesMoved == 0, "token gate moves no bytes");
static_assert(kSwarmTokenGateTokens == 0, "token gate invents no tokens");
static_assert(kSwarmTokenGateUnmeasuredMs < 0, "latency sentinel stays negative");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_LIMITS_H
