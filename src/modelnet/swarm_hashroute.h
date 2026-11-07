// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHROUTE_H
#define BITCOIN_MODELNET_SWARM_HASHROUTE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmHashRoute {
    std::string route_id;
    bool hashlock{false};
    bool want_route{false};
};

struct SwarmHashRouteResult {
    std::string code;
    bool routed{false};
    int64_t bytes_moved{0};
};

SwarmHashRouteResult SwarmNoteHashRoute(const SwarmHashRoute& route, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHROUTE_H
