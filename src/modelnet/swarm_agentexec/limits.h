// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_LIMITS_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_LIMITS_H

#include <cstdint>

namespace modelnet {

/** No child process exists. launched() stays false. */
inline constexpr bool kSwarmAgentExecLaunched = false;

/** This executor does not open a socket. connected() stays false. */
inline constexpr bool kSwarmAgentExecConnected = false;

/** This executor does not claim a GPU ran. gpu() stays false. */
inline constexpr bool kSwarmAgentExecGpu = false;

/** This executor does not broadcast. broadcast() stays false. */
inline constexpr bool kSwarmAgentExecBroadcast = false;

/** This executor moves no atoms. */
inline constexpr int64_t kSwarmAgentExecAtomsMoved = 0;

/** This executor does not spend. The text is the digit zero. */
inline constexpr char kSwarmAgentExecAutomaticSpend[] = "0";

/**
 * Paths that begin with these bytes are private.
 * The check is bytewise. An Allow of this prefix does not make Execute succeed.
 */
inline constexpr char kSwarmAgentExecPrivatePrefix[] = "private/";

/** Tool name that is refused before any path is considered. */
inline constexpr char kSwarmAgentExecToolNet[] = "net";

/** Tool name that hashes a payload inside this process. */
inline constexpr char kSwarmAgentExecToolSha256[] = "sha256";

static_assert(!kSwarmAgentExecLaunched, "agent exec does not launch");
static_assert(!kSwarmAgentExecConnected, "agent exec does not connect");
static_assert(!kSwarmAgentExecGpu, "agent exec does not use a gpu");
static_assert(!kSwarmAgentExecBroadcast, "agent exec does not broadcast");
static_assert(kSwarmAgentExecAtomsMoved == 0, "agent exec moves no atoms");
static_assert(kSwarmAgentExecAutomaticSpend[0] == '0', "spend stays zero");
static_assert(kSwarmAgentExecAutomaticSpend[1] == '\0', "spend stays zero");
static_assert(kSwarmAgentExecPrivatePrefix[0] == 'p', "private prefix");
static_assert(kSwarmAgentExecPrivatePrefix[7] == '/', "private prefix ends in slash");
static_assert(kSwarmAgentExecPrivatePrefix[8] == '\0', "private prefix length");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_LIMITS_H
