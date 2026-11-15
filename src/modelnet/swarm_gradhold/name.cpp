// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/name.h>

namespace modelnet {

std::string SwarmGradHoldName::copy(const std::string& update_id) const
{
    if (update_id.empty()) return {};
    return update_id;
}

} // namespace modelnet
