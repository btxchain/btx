// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/niche.h>

namespace modelnet {

bool DescendantNicheKnown(const std::string& channel)
{
    return channel == "general" || channel == "coding" || channel == "research";
}

} // namespace modelnet
