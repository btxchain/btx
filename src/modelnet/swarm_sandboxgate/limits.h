// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane does not launch a process. */
inline constexpr bool kSwarmSandboxGateLaunched = false;

/** This plane does not open a socket. */
inline constexpr bool kSwarmSandboxGateConnected = false;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmSandboxGateGpu = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmSandboxGateBytesMoved = 0;

/** This plane does not spend. The text is the digit zero. */
inline constexpr char kSwarmSandboxGateAutomaticSpend[] = "0";

/**
 * Paths that begin with these bytes are private.
 * The check is bytewise. A grant of this prefix does not allow the action.
 */
inline constexpr char kSwarmSandboxGatePrivatePrefix[] = "private/";

static_assert(!kSwarmSandboxGateLaunched, "sandbox gate does not launch");
static_assert(!kSwarmSandboxGateConnected, "sandbox gate does not connect");
static_assert(!kSwarmSandboxGateGpu, "sandbox gate does not use a gpu");
static_assert(kSwarmSandboxGateBytesMoved == 0, "sandbox gate moves no bytes");
static_assert(kSwarmSandboxGateAutomaticSpend[0] == '0', "spend stays zero");
static_assert(kSwarmSandboxGateAutomaticSpend[1] == '\0', "spend stays zero");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_LIMITS_H
