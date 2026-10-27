// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/blank.h>

#include <modelnet/swarm_natpub/codes.h>

namespace modelnet {

bool SwarmNatPubBlank::accept(const std::string& endpoint, std::string& err) const
{
    if (endpoint.empty()) {
        err = kSwarmNatPubEndpoint;
        return false;
    }
    return true;
}

} // namespace modelnet
