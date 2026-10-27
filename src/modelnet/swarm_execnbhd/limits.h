// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Lowest-RTT peers seated into the nearby set. */
inline constexpr int64_t kSwarmExecNbhdNearbyCap = 4;

/** Peers seated from trust domains absent in the nearby set. */
inline constexpr int64_t kSwarmExecNbhdRemoteCap = 2;

/** This plane does not connect. */
inline constexpr bool kSwarmExecNbhdConnected = false;

/** This plane does not open a socket. */
inline constexpr bool kSwarmExecNbhdSocketOpened = false;

/** This plane does not launch a process. */
inline constexpr bool kSwarmExecNbhdLaunched = false;

/** This plane does not use a GPU. */
inline constexpr bool kSwarmExecNbhdGpu = false;

/** This plane does not broadcast. */
inline constexpr bool kSwarmExecNbhdBroadcast = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmExecNbhdBytesMoved = 0;

/** This plane moves no atoms. */
inline constexpr int64_t kSwarmExecNbhdAtomsMoved = 0;

/** This plane does not spend. The text is the zero amount. */
inline constexpr char kSwarmExecNbhdAutomaticSpend[] = "0";

static_assert(kSwarmExecNbhdNearbyCap == 4, "nearby cap is 4");
static_assert(kSwarmExecNbhdRemoteCap == 2, "remote cap is 2");
static_assert(!kSwarmExecNbhdConnected, "connected stays false");
static_assert(!kSwarmExecNbhdSocketOpened, "socket stays closed");
static_assert(!kSwarmExecNbhdLaunched, "launched stays false");
static_assert(!kSwarmExecNbhdGpu, "gpu stays false");
static_assert(!kSwarmExecNbhdBroadcast, "broadcast stays false");
static_assert(kSwarmExecNbhdBytesMoved == 0, "bytes stay 0");
static_assert(kSwarmExecNbhdAtomsMoved == 0, "atoms stay 0");
static_assert(kSwarmExecNbhdAutomaticSpend[0] == '0', "spend stays 0");
static_assert(kSwarmExecNbhdAutomaticSpend[1] == '\0', "spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_LIMITS_H
