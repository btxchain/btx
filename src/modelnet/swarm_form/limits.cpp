// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/limits.h>

namespace modelnet {

bool SwarmFormLimits::bytes_moved() const
{
    return false;
}

bool SwarmFormLimits::launched_sidecar() const
{
    return false;
}

std::vector<std::string> SwarmFormLimits::dns_seeds() const
{
    return {};
}

} // namespace modelnet
