// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WANUPDATE_H
#define BITCOIN_MODELNET_SWARM_WANUPDATE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmWanUpdate {
    std::string island_id;
    bool want_exchange;
};

struct SwarmWanUpdateResult {
    std::string code;
    bool exchanged;
    int64_t bytes_moved;
};

SwarmWanUpdateResult SwarmNoteWanUpdate(const SwarmWanUpdate& island, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WANUPDATE_H
