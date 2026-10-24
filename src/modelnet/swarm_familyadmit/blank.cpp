// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/blank.h>

namespace modelnet {

bool SwarmFamilyAdmitBlank(const std::string& peer, const std::string& family)
{
    return peer.empty() || family.empty();
}

} // namespace modelnet
