// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/blank.h>

#include <modelnet/swarm_schedwit/codes.h>

namespace modelnet {

bool SwarmSchedWitnessBlank::accept(const std::string& witness, std::string& err) const
{
    if (witness.empty()) {
        err = kSwarmSchedWitnessWitness;
        return false;
    }
    return true;
}

} // namespace modelnet
