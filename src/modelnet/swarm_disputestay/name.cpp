// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/name.h>

namespace modelnet {

std::string SwarmDisputeStayName::copy(const std::string& dispute) const
{
    if (dispute.empty()) return {};
    return dispute;
}

} // namespace modelnet
