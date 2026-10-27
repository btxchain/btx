// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRESENCE_H
#define BITCOIN_MODELNET_SWARM_PRESENCE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmLocalPresenceRequest {
    std::string node_id;
    int64_t rtt_ms;
    bool new_domain;
    bool want_connect;
};

struct SwarmPresenceResult {
    std::string code;
    bool connected;
    bool published;
    int64_t kept;
};

SwarmPresenceResult SwarmAcceptPresenceLocal(const SwarmLocalPresenceRequest& presence, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRESENCE_H
