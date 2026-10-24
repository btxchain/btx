// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/seal.h>

#include <modelnet/swarm_gradhold/codes.h>
#include <modelnet/swarm_gradhold/limits.h>

namespace modelnet {

std::string SwarmGradHoldSeal::refusal(const std::string& update_id) const
{
    if (update_id.empty()) return std::string{kSwarmGradHoldUpdate};
    return std::string{kSwarmGradHoldNotExported};
}

bool SwarmGradHoldSeal::exported() const
{
    return kSwarmGradHoldExported;
}

} // namespace modelnet
