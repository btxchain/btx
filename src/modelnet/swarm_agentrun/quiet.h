// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_QUIET_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/** launched() stays this value. No method sets it true. */
inline constexpr bool kAgentRunLaunched = false;

/** gpu() stays this value. This plane does not use a gpu. */
inline constexpr bool kAgentRunGpu = false;

/** bytes_moved() stays this value. */
inline constexpr int64_t kAgentRunBytesMoved = 0;

/** atoms_moved() stays this value. */
inline constexpr int64_t kAgentRunAtomsMoved = 0;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kAgentRunAutomaticSpend[] = "0";

/** broadcast() stays this value. Nothing is broadcast. */
inline constexpr bool kAgentRunBroadcast = false;

static_assert(!kAgentRunLaunched, "the plane does not launch");
static_assert(!kAgentRunGpu, "the plane does not use a gpu");
static_assert(kAgentRunBytesMoved == 0, "the plane moves no bytes");
static_assert(kAgentRunAtomsMoved == 0, "the plane moves no atoms");
static_assert(!kAgentRunBroadcast, "the plane does not broadcast");
static_assert(kAgentRunAutomaticSpend[0] == '0' && kAgentRunAutomaticSpend[1] == '\0', "automatic spend stays 0");

/**
 * Fixed observers. There is no setter.
 * launched() stays false. gpu() stays false. bytes_moved() stays 0.
 * atoms_moved() stays 0. automatic_spend() stays "0". broadcast() stays false.
 */
class SwarmAgentRunQuiet {
public:
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool broadcast() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_QUIET_H
