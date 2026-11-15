// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/hub.h>

#include <modelnet/swarm_parentage/codes.h>

#include <string>

namespace modelnet {

bool SwarmParentageClassifyHub(const std::string& checkpoint, const std::string& card, std::string& err)
{
    // The checkpoint id is not consulted. A card never becomes a parent.
    static_cast<void>(checkpoint.size());
    if (card.empty()) {
        err = SWARM_PARENTAGE_CARD;
        return false;
    }
    err = SWARM_PARENTAGE_NOT_AUTHORITY;
    return false;
}

} // namespace modelnet
