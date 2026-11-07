// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHURNNOTE_H
#define BITCOIN_MODELNET_SWARM_CHURNNOTE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmChurnNote {
    std::string peer_id;
    bool churned;
    bool want_send;
};

struct SwarmChurnNoteResult {
    std::string code;
    bool sent;
    int64_t bytes_moved;
};

SwarmChurnNoteResult SwarmNoteChurn(const SwarmChurnNote& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHURNNOTE_H
