// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/stay.h>

#include <modelnet/swarm_schedwit/codes.h>
#include <modelnet/swarm_schedwit/limits.h>

namespace modelnet {

std::string SwarmSchedWitnessStay::refusal() const
{
    return std::string{kSwarmSchedWitnessNotSigned};
}

bool SwarmSchedWitnessStay::signed_ok() const
{
    return kSwarmSchedWitnessSignedOk;
}

} // namespace modelnet
