// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/flags.h>

#include <cstdint>
#include <string>

namespace modelnet {

namespace {

inline constexpr bool kSwarmSettleBuildQualified = false;
inline constexpr bool kSwarmSettleBuildBroadcast = false;
inline constexpr bool kSwarmSettleBuildLaunched = false;
inline constexpr bool kSwarmSettleBuildGpu = false;
inline constexpr int64_t kSwarmSettleBuildAtomsMoved = 0;
inline constexpr char kSwarmSettleBuildAutomaticSpend[] = "0";
inline constexpr bool kSwarmSettleBuildSecpPenalty = false;

static_assert(!kSwarmSettleBuildQualified, "qualified stays false");
static_assert(!kSwarmSettleBuildBroadcast, "broadcast stays false");
static_assert(!kSwarmSettleBuildLaunched, "launched stays false");
static_assert(!kSwarmSettleBuildGpu, "gpu stays false");
static_assert(kSwarmSettleBuildAtomsMoved == 0, "atoms moved stay 0");
static_assert(kSwarmSettleBuildAutomaticSpend[0] == '0', "automatic spend stays 0");
static_assert(kSwarmSettleBuildAutomaticSpend[1] == '\0', "automatic spend is the string 0");
static_assert(!kSwarmSettleBuildSecpPenalty, "secp penalty stays false");

} // namespace

bool SwarmSettleBuildFlags::qualified() const
{
    return kSwarmSettleBuildQualified;
}

bool SwarmSettleBuildFlags::broadcast() const
{
    return kSwarmSettleBuildBroadcast;
}

bool SwarmSettleBuildFlags::launched() const
{
    return kSwarmSettleBuildLaunched;
}

bool SwarmSettleBuildFlags::gpu() const
{
    return kSwarmSettleBuildGpu;
}

int64_t SwarmSettleBuildFlags::atoms_moved() const
{
    return kSwarmSettleBuildAtomsMoved;
}

std::string SwarmSettleBuildFlags::automatic_spend() const
{
    return std::string(kSwarmSettleBuildAutomaticSpend);
}

bool SwarmSettleBuildFlags::secp_penalty() const
{
    return kSwarmSettleBuildSecpPenalty;
}

} // namespace modelnet
