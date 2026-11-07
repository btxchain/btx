// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/flags.h>

#include <modelnet/swarm_sigcover/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmSigCoverFlags::signed_ok() const
{
    return kSwarmSigCoverSignedOk;
}

bool SwarmSigCoverFlags::secp_penalty() const
{
    return kSwarmSigCoverSecpPenalty;
}

bool SwarmSigCoverFlags::broadcast() const
{
    return kSwarmSigCoverBroadcast;
}

bool SwarmSigCoverFlags::launched() const
{
    return kSwarmSigCoverLaunched;
}

bool SwarmSigCoverFlags::gpu() const
{
    return kSwarmSigCoverGpu;
}

int64_t SwarmSigCoverFlags::atoms_moved() const
{
    return kSwarmSigCoverAtomsMoved;
}

std::string SwarmSigCoverFlags::automatic_spend() const
{
    return std::string(kSwarmSigCoverAutomaticSpend);
}

} // namespace modelnet
