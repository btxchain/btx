// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/name.h>

namespace modelnet {

std::string SwarmGuestHoldName::copy(const std::string& name) const
{
    if (name.empty()) return {};
    return name;
}

} // namespace modelnet
