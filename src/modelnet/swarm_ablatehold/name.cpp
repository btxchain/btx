// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/name.h>

namespace modelnet {

std::string SwarmAblateHoldName::copy(const std::string& name) const
{
    if (name.empty()) return {};
    return name;
}

} // namespace modelnet
