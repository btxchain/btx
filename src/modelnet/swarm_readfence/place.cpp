// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/place.h>

#include <modelnet/swarm_readfence/codes.h>

namespace modelnet {

bool SwarmReadPlace::Apply(SwarmReadBook& book, const std::string& page, const std::string& family, std::string& err) const
{
    if (page.empty() || family.empty() || !book.Place(page, family)) {
        err = kSwarmReadPage;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
