// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/quiet.h>

#include <modelnet/swarm_evalengine/limits.h>

namespace modelnet {

bool SwarmEvaluationQuiet::launched() const
{
    return kSwarmEvaluationLaunched;
}

bool SwarmEvaluationQuiet::gpu() const
{
    return kSwarmEvaluationGpu;
}

std::uint64_t SwarmEvaluationQuiet::bytes_moved() const
{
    return kSwarmEvaluationBytesMoved;
}

std::uint64_t SwarmEvaluationQuiet::atoms_moved() const
{
    return kSwarmEvaluationAtomsMoved;
}

std::string SwarmEvaluationQuiet::automatic_spend() const
{
    return std::string{kSwarmEvaluationAutomaticSpend};
}

bool SwarmEvaluationQuiet::broadcast() const
{
    return kSwarmEvaluationBroadcast;
}

bool SwarmEvaluationQuiet::realm_promoted() const
{
    return kSwarmEvaluationRealmPromoted;
}

bool SwarmEvaluationQuiet::exact_replay_admitted() const
{
    return kSwarmEvaluationExactReplayAdmitted;
}

bool SwarmEvaluationQuiet::money() const
{
    return kSwarmEvaluationMoney;
}

} // namespace modelnet
