// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/name.h>

namespace modelnet {

std::string SwarmNatPubName::copy(const std::string& endpoint) const
{
    if (endpoint.empty()) return {};
    return endpoint;
}

} // namespace modelnet
