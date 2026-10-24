// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MANIFESTBIND_H
#define BTX_MODELNET_SWARM_MANIFESTBIND_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmManifestBind {
    std::string root_id;
    int64_t children{0};
    int64_t matched{0};
    bool want_activate{false};
};

struct SwarmManifestBindResult {
    std::string code;
    bool activated{false};
    bool bytes_streamed{false};
};

/** A manifest root stays inactive until every child matches, and this record streams nothing. */
SwarmManifestBindResult SwarmBindChildren(const SwarmManifestBind& bind, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MANIFESTBIND_H
