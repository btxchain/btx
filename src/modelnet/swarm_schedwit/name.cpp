// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/name.h>

namespace modelnet {

std::string SwarmSchedWitnessName::copy(const std::string& witness) const
{
    if (witness.empty()) return {};
    return witness;
}

} // namespace modelnet
